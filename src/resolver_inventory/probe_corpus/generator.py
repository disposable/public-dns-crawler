"""Probe corpus generation from official seed snapshots."""

from __future__ import annotations

from collections import defaultdict

from resolver_inventory import __version__
from resolver_inventory.probe_corpus.models import (
    GeneratedProbeCandidate,
    GeneratedProbeCorpusResult,
    ProbeGenerationReport,
    SeedSnapshot,
)
from resolver_inventory.probe_corpus.schema import ProbeCorpus, ProbeDefinition
from resolver_inventory.probe_corpus.validators import (
    BaselineResolverClient,
    UdpBaselineResolverClient,
    validate_generated_probe_corpus,
    validate_generation_thresholds,
    validate_probe_candidate,
)
from resolver_inventory.settings import ProbeCorpusConfig
from resolver_inventory.util.time import utc_now_iso


def generate_probe_corpus(
    config: ProbeCorpusConfig,
    seed_snapshot: SeedSnapshot,
    client: BaselineResolverClient | None = None,
) -> GeneratedProbeCorpusResult:
    client = client or UdpBaselineResolverClient()
    report = ProbeGenerationReport(baseline_resolvers_used=list(config.baseline.resolvers))
    candidates: list[GeneratedProbeCandidate] = []
    candidates.extend(_generate_positive_exact_probes(config, seed_snapshot))
    candidates.extend(_generate_positive_consensus_probes(seed_snapshot))
    candidates.extend(_generate_negative_generated_probes(config))

    probes: list[ProbeDefinition] = []
    for candidate in candidates:
        report.record_candidate(candidate)
        validation = validate_probe_candidate(candidate, config, client)
        if validation.accepted:
            _apply_validation_metadata(candidate.probe, validation)
            probes.append(candidate.probe)
            report.record_accept(candidate, validation)
        else:
            report.record_rejection(candidate, validation)

    corpus = ProbeCorpus(
        schema_version=config.schema_version,
        corpus_version=config.corpus_version,
        generated_at=utc_now_iso(),
        generator_version=__version__,
        sources_used=list(seed_snapshot.sources_used),
        probe_counts=_count_probes(probes),
        probes=probes,
    )
    validate_generation_thresholds(report, config)
    validate_generated_probe_corpus(corpus)
    return GeneratedProbeCorpusResult(corpus=corpus, report=report)


def _generate_positive_exact_probes(
    config: ProbeCorpusConfig,
    seed_snapshot: SeedSnapshot,
) -> list[GeneratedProbeCandidate]:
    probes: list[GeneratedProbeCandidate] = []
    per_zone_counts: dict[str, int] = defaultdict(int)
    per_family_counts: dict[str, int] = defaultdict(int)

    for root in seed_snapshot.root_servers:
        probes.extend(
            _exact_probes_for_host(
                zone="root",
                hostname=root.hostname,
                ipv4=root.ipv4,
                ipv6=root.ipv6,
                source=root.source,
                notes=root.notes,
                operator_family=root.operator_family or root.hostname,
                per_zone_counts=per_zone_counts,
                per_family_counts=per_family_counts,
                config=config,
            )
        )

    for delegation in seed_snapshot.delegations:
        for host in delegation.exact_hosts:
            probes.extend(
                _exact_probes_for_host(
                    zone=delegation.zone,
                    hostname=host.hostname,
                    ipv4=host.ipv4,
                    ipv6=host.ipv6,
                    source=host.source or delegation.source,
                    notes=host.notes or delegation.notes,
                    operator_family=host.operator_family or delegation.zone,
                    per_zone_counts=per_zone_counts,
                    per_family_counts=per_family_counts,
                    config=config,
                )
            )
    return probes


def _exact_probes_for_host(
    *,
    zone: str,
    hostname: str,
    ipv4: list[str],
    ipv6: list[str],
    source: str,
    notes: str | None,
    operator_family: str,
    per_zone_counts: dict[str, int],
    per_family_counts: dict[str, int],
    config: ProbeCorpusConfig,
) -> list[GeneratedProbeCandidate]:
    if per_zone_counts[zone] >= config.selection.max_per_tld:
        return []
    if per_family_counts[operator_family] >= config.selection.max_per_operator_family:
        return []

    created: list[GeneratedProbeCandidate] = []
    if ipv4 and per_zone_counts[zone] < config.selection.max_per_tld:
        created.append(
            GeneratedProbeCandidate(
                probe=ProbeDefinition(
                    id=_probe_id("positive-exact", hostname, "A"),
                    kind="positive_exact",
                    qname=hostname,
                    qtype="A",
                    expected_mode="exact_rrset",
                    expected_answers=list(ipv4),
                    source=source,
                    notes=notes,
                    stability_score=1.0,
                ),
                source=source,
                original_seed=hostname,
                kind="positive_exact",
            )
        )
        per_zone_counts[zone] += 1
    if ipv6 and per_zone_counts[zone] < config.selection.max_per_tld:
        created.append(
            GeneratedProbeCandidate(
                probe=ProbeDefinition(
                    id=_probe_id("positive-exact", hostname, "AAAA"),
                    kind="positive_exact",
                    qname=hostname,
                    qtype="AAAA",
                    expected_mode="exact_rrset",
                    expected_answers=list(ipv6),
                    source=source,
                    notes=notes,
                    stability_score=1.0,
                ),
                source=source,
                original_seed=hostname,
                kind="positive_exact",
            )
        )
        per_zone_counts[zone] += 1
    if created:
        per_family_counts[operator_family] += 1
    return created


def _generate_positive_consensus_probes(
    seed_snapshot: SeedSnapshot,
) -> list[GeneratedProbeCandidate]:
    probes: list[GeneratedProbeCandidate] = []
    for delegation in seed_snapshot.delegations:
        probes.append(
            GeneratedProbeCandidate(
                probe=ProbeDefinition(
                    id=_probe_id("positive-consensus", delegation.zone, "NS"),
                    kind="positive_consensus",
                    qname=delegation.zone,
                    qtype="NS",
                    expected_mode="consensus_match",
                    expected_nameservers=list(delegation.nameservers),
                    source=delegation.source,
                    notes=delegation.notes,
                    stability_score=0.9,
                ),
                source=delegation.source,
                original_seed=delegation.zone,
                kind="positive_consensus",
            )
        )
    return probes


def _generate_negative_generated_probes(config: ProbeCorpusConfig) -> list[GeneratedProbeCandidate]:
    probes: list[GeneratedProbeCandidate] = []
    for parent_zone in config.negative.parent_zones:
        validate_negative_parent_zone_config(parent_zone)
        probes.append(
            GeneratedProbeCandidate(
                probe=ProbeDefinition(
                    id=_probe_id("negative-generated", parent_zone, "A"),
                    kind="negative_generated",
                    qtype="A",
                    expected_mode="nxdomain",
                    qname_template="{uuid}." + parent_zone.rstrip(".") + ".",
                    parent_zone=parent_zone,
                    source="negative-parent-pool",
                    stability_score=0.8,
                ),
                source="negative-parent-pool",
                original_seed=parent_zone,
                kind="negative_generated",
            )
        )
    return probes


def validate_negative_parent_zone_config(parent_zone: str) -> None:
    if not parent_zone.endswith("."):
        raise ValueError(f"negative parent zone must be absolute: {parent_zone}")


def _probe_id(prefix: str, name: str, qtype: str) -> str:
    normalized = name.rstrip(".").replace(".", "-").lower()
    return f"{prefix}-{normalized}-{qtype.lower()}"


def _count_probes(probes: list[ProbeDefinition]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for probe in probes:
        counts[probe.kind] = counts.get(probe.kind, 0) + 1
    return counts


def _apply_validation_metadata(
    probe: ProbeDefinition,
    validation,
) -> None:
    # `expected_nameservers` remains generation metadata for consensus probes.
    if validation.agreed_answers:
        probe.expected_answers = list(validation.agreed_answers)
    if validation.agreed_nameservers:
        probe.expected_nameservers = list(validation.agreed_nameservers)
