"""Abstractions for plain-DNS probe execution backends."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
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


PlainDnsExecutionCallback = Callable[[PlainDnsProbeExecution], Awaitable[None]]


def supports_massdns_phase1(spec: PlainDnsProbeSpec) -> bool:
    return spec.candidate_transport == "dns-udp" and spec.port == 53


async def run_python_plain_dns_batch(
    specs: list[PlainDnsProbeSpec],
    *,
    timeout_s: float,
    baseline_resolvers: list[str],
    baseline_cache: dict[tuple[str, str], list[str]],
    parallelism: int,
    on_execution: PlainDnsExecutionCallback | None = None,
) -> list[PlainDnsProbeExecution]:
    if not specs:
        return []

    semaphore = asyncio.Semaphore(max(1, parallelism))
    out: list[PlainDnsProbeExecution] = []

    async def _run_one(spec: PlainDnsProbeSpec) -> PlainDnsProbeExecution:
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
            return PlainDnsProbeExecution(spec=spec, result=result)

    for future in asyncio.as_completed([_run_one(spec) for spec in specs]):
        execution = await future
        if on_execution is not None:
            await on_execution(execution)
        else:
            out.append(execution)
    return out


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
