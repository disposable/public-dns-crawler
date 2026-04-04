"""Canonical data models for resolver-inventory."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Transport = Literal["dns-udp", "dns-tcp", "doh"]
Status = Literal["accepted", "candidate", "rejected"]
FilterReason = Literal[
    "source_reliability_below_min",
    "invalid_dns_host",
    "duplicate_dns_candidate",
    "invalid_doh_url",
    "duplicate_doh_candidate",
]
FilterStage = Literal["source", "normalize"]


@dataclass(slots=True)
class Candidate:
    """A discovered resolver endpoint, before validation."""

    provider: str | None
    source: str
    transport: Transport
    endpoint_url: str | None
    host: str
    port: int
    path: str | None
    bootstrap_ipv4: list[str] = field(default_factory=list)
    bootstrap_ipv6: list[str] = field(default_factory=list)
    tls_server_name: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)

    def __str__(self) -> str:
        if self.transport == "doh":
            return f"doh:{self.endpoint_url}"
        return f"{self.transport}:{self.host}:{self.port}"


@dataclass(slots=True)
class FilteredCandidate:
    """A candidate that was dropped before validation."""

    candidate: Candidate
    reason: FilterReason
    detail: str
    stage: FilterStage


@dataclass(slots=True)
class DiscoveryResult:
    """Discovery output plus candidates filtered before validation."""

    candidates: list[Candidate]
    filtered: list[FilteredCandidate] = field(default_factory=list)


@dataclass(slots=True)
class ProbeResult:
    """Result of a single validation probe against a candidate."""

    ok: bool
    probe: str
    latency_ms: float | None = None
    error: str | None = None
    details: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class ValidationResult:
    """Aggregated validation outcome for one candidate."""

    candidate: Candidate
    accepted: bool
    score: int
    status: Status
    reasons: list[str]
    probes: list[ProbeResult]

    def median_latency_ms(self) -> float | None:
        """Return median latency across successful probes, or None."""
        latencies = [p.latency_ms for p in self.probes if p.ok and p.latency_ms is not None]
        if not latencies:
            return None
        latencies.sort()
        mid = len(latencies) // 2
        if len(latencies) % 2 == 0:
            return (latencies[mid - 1] + latencies[mid]) / 2.0
        return latencies[mid]
