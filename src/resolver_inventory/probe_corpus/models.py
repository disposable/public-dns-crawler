"""Internal models for probe corpus seed ingestion and generation."""

from __future__ import annotations

from dataclasses import dataclass, field

from resolver_inventory.probe_corpus.schema import ProbeCorpus, ProbeDefinition


@dataclass(slots=True)
class ExactHostSeed:
    hostname: str
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    source: str = ""
    operator_family: str | None = None
    notes: str | None = None


@dataclass(slots=True)
class DelegationSeed:
    zone: str
    nameservers: list[str]
    exact_hosts: list[ExactHostSeed] = field(default_factory=list)
    source: str = ""
    notes: str | None = None


@dataclass(slots=True)
class RootServerSeed:
    hostname: str
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    source: str = ""
    operator_family: str | None = None
    notes: str | None = None


@dataclass(slots=True)
class SeedSnapshot:
    snapshot_version: int
    generated_at: str
    sources_used: list[str]
    root_servers: list[RootServerSeed] = field(default_factory=list)
    delegations: list[DelegationSeed] = field(default_factory=list)


@dataclass(slots=True)
class GeneratedProbeCandidate:
    probe: ProbeDefinition
    source: str
    original_seed: str
    kind: str


@dataclass(slots=True)
class GeneratedProbeValidation:
    accepted: bool
    rejection_reason: str | None = None
    details: dict[str, str] = field(default_factory=dict)
    agreed_answers: list[str] = field(default_factory=list)
    agreed_nameservers: list[str] = field(default_factory=list)


@dataclass(slots=True)
class GeneratedProbeAccepted:
    candidate: GeneratedProbeCandidate
    validation: GeneratedProbeValidation

    @property
    def probe(self) -> ProbeDefinition:
        return self.candidate.probe


@dataclass(slots=True)
class ProbeGenerationReport:
    total_candidates: int = 0
    accepted_count: int = 0
    rejected_count: int = 0
    candidate_counts: dict[str, int] = field(default_factory=dict)
    accepted_counts: dict[str, int] = field(default_factory=dict)
    rejected_counts: dict[str, int] = field(default_factory=dict)
    rejected_by_reason: dict[str, int] = field(default_factory=dict)
    baseline_resolvers_used: list[str] = field(default_factory=list)
    accepted_probes: list[GeneratedProbeAccepted] = field(default_factory=list)
    rejected_candidates: list[tuple[GeneratedProbeCandidate, GeneratedProbeValidation]] = field(
        default_factory=list
    )

    def record_candidate(self, candidate: GeneratedProbeCandidate) -> None:
        self.total_candidates += 1
        self.candidate_counts[candidate.kind] = self.candidate_counts.get(candidate.kind, 0) + 1

    def record_accept(
        self,
        candidate: GeneratedProbeCandidate,
        validation: GeneratedProbeValidation,
    ) -> None:
        self.accepted_count += 1
        self.accepted_counts[candidate.kind] = self.accepted_counts.get(candidate.kind, 0) + 1
        self.accepted_probes.append(GeneratedProbeAccepted(candidate, validation))

    def record_rejection(
        self,
        candidate: GeneratedProbeCandidate,
        validation: GeneratedProbeValidation,
    ) -> None:
        self.rejected_count += 1
        self.rejected_counts[candidate.kind] = self.rejected_counts.get(candidate.kind, 0) + 1
        if validation.rejection_reason:
            self.rejected_by_reason[validation.rejection_reason] = (
                self.rejected_by_reason.get(validation.rejection_reason, 0) + 1
            )
        self.rejected_candidates.append((candidate, validation))


@dataclass(slots=True)
class GeneratedProbeCorpusResult:
    corpus: ProbeCorpus
    report: ProbeGenerationReport
