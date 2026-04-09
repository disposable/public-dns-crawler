"""Abstractions for plain-DNS probe execution backends."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Literal, Protocol

from resolver_inventory.models import ProbeResult
from resolver_inventory.validate.corpus import CorpusEntry
from resolver_inventory.validate.dns_plain import _probe_nxdomain, _probe_positive

PlainDnsProbeKind = Literal["positive", "nxdomain"]


@dataclass(frozen=True, slots=True)
class PlainDnsProbeSpec:
    probe_id: str
    kind: PlainDnsProbeKind
    candidate_idx: int
    candidate_transport: str
    host: str
    port: int
    qname: str
    rdtype: str
    probe_name: str
    is_nxdomain_probe: bool
    expected_answers: list[str]
    baseline_key: tuple[str, str] | None
    entry: CorpusEntry


@dataclass(frozen=True, slots=True)
class PlainDnsProbeExecution:
    spec: PlainDnsProbeSpec
    result: ProbeResult


class PlainDnsBatchRunner(Protocol):
    async def __call__(
        self,
        specs: list[PlainDnsProbeSpec],
        *,
        timeout_s: float,
        baseline_resolvers: list[str],
        baseline_cache: dict[tuple[str, str], list[str]],
        parallelism: int,
    ) -> list[PlainDnsProbeExecution]: ...


def supports_massdns_phase1(spec: PlainDnsProbeSpec) -> bool:
    return spec.candidate_transport == "dns-udp" and spec.port == 53


async def run_python_plain_dns_batch(
    specs: list[PlainDnsProbeSpec],
    *,
    timeout_s: float,
    baseline_resolvers: list[str],
    baseline_cache: dict[tuple[str, str], list[str]],
    parallelism: int,
) -> list[PlainDnsProbeExecution]:
    if not specs:
        return []

    semaphore = asyncio.Semaphore(max(1, parallelism))
    out: list[PlainDnsProbeExecution | None] = [None] * len(specs)

    async def _run_at(index: int, spec: PlainDnsProbeSpec) -> None:
        async with semaphore:
            if spec.kind == "positive":
                result = await _probe_positive(
                    spec.entry,
                    spec.host,
                    spec.port,
                    spec.candidate_transport,
                    timeout_s,
                    baseline_resolvers,
                    baseline_cache,
                )
            else:
                result = await _probe_nxdomain(
                    spec.entry,
                    spec.host,
                    spec.port,
                    spec.candidate_transport,
                    timeout_s,
                )
            out[index] = PlainDnsProbeExecution(spec=spec, result=result)

    await asyncio.gather(*(_run_at(index, spec) for index, spec in enumerate(specs)))
    return [item for item in out if item is not None]


def build_python_backend_error_probe(
    spec: PlainDnsProbeSpec,
    error: str,
) -> PlainDnsProbeExecution:
    return PlainDnsProbeExecution(
        spec=spec,
        result=ProbeResult(ok=False, probe=spec.probe_name, error=error),
    )


def map_backend_results_to_probe_results(
    executions: list[PlainDnsProbeExecution],
) -> list[ProbeResult]:
    return [execution.result for execution in executions]


def map_backend_results_by_candidate(
    executions: list[PlainDnsProbeExecution],
) -> dict[int, list[ProbeResult]]:
    grouped: dict[int, list[ProbeResult]] = {}
    for execution in executions:
        grouped.setdefault(execution.spec.candidate_idx, []).append(execution.result)
    return grouped
