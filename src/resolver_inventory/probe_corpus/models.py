"""Internal models for probe corpus seed ingestion and generation."""

from __future__ import annotations

from dataclasses import dataclass, field


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
