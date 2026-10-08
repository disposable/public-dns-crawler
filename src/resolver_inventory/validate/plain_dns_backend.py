"""Abstractions for plain-DNS probe execution backends."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal, Protocol

import dns.edns
import dns.message
import dns.rdatatype

from resolver_inventory.models import ProbeResult
from resolver_inventory.settings import CapabilitiesConfig
from resolver_inventory.validate.capabilities import run_capability_check
from resolver_inventory.validate.corpus import CorpusEntry
from resolver_inventory.validate.dns_plain import (
    _probe_nxdomain,
    _probe_positive,
    _query_tcp,
    _query_udp,
)

PlainDnsProbeKind = Literal["positive", "nxdomain", "capability"]


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
    capability_name: str = ""


@dataclass(frozen=True, slots=True)
class PlainDnsProbeExecution:
    spec: PlainDnsProbeSpec
    result: ProbeResult


PlainDnsExecutionCallback = Callable[[PlainDnsProbeExecution], Awaitable[None]]


class PlainDnsBatchRunner(Protocol):
    async def __call__(
        self,
        specs: list[PlainDnsProbeSpec],
        *,
        timeout_s: float,
        baseline_resolvers: list[str],
        baseline_cache: dict[tuple[str, str], list[str]],
        parallelism: int,
        capabilities_config: CapabilitiesConfig | None = None,
        on_execution: PlainDnsExecutionCallback | None = None,
    ) -> list[PlainDnsProbeExecution]: ...


def supports_massdns_phase1(spec: PlainDnsProbeSpec) -> bool:
    # Capability specs always run through the python backend: they need
    # per-check evaluation (and EDNS options) that massdns cannot express.
    return spec.kind != "capability" and spec.candidate_transport == "dns-udp" and spec.port == 53


def plain_dns_probe_spec_to_dict(spec: PlainDnsProbeSpec) -> dict[str, Any]:
    return {
        "probe_id": spec.probe_id,
        "kind": spec.kind,
        "candidate_idx": spec.candidate_idx,
        "candidate_transport": spec.candidate_transport,
        "host": spec.host,
        "port": spec.port,
        "qname": spec.qname,
        "rdtype": spec.rdtype,
        "probe_name": spec.probe_name,
        "is_nxdomain_probe": spec.is_nxdomain_probe,
        "expected_answers": spec.expected_answers,
        "baseline_key": list(spec.baseline_key) if spec.baseline_key is not None else None,
        "capability_name": spec.capability_name,
        "entry": {
            "rdtype": spec.entry.rdtype,
            "qname": spec.entry.qname,
            "qname_template": spec.entry.qname_template,
            "expected_mode": spec.entry.expected_mode,
            "expected_rcode": spec.entry.expected_rcode,
            "expected_answers": spec.entry.expected_answers,
            "expected_nameservers": spec.entry.expected_nameservers,
            "parent_zone": spec.entry.parent_zone,
            "nxdomain": spec.entry.nxdomain,
            "label": spec.entry.label,
            "source": spec.entry.source,
            "stability_score": spec.entry.stability_score,
            "notes": spec.entry.notes,
        },
    }


def plain_dns_probe_spec_from_dict(data: dict[str, Any]) -> PlainDnsProbeSpec:
    entry_data = data["entry"]
    entry = CorpusEntry(
        rdtype=entry_data["rdtype"],
        qname=entry_data.get("qname"),
        qname_template=entry_data.get("qname_template"),
        expected_mode=entry_data.get("expected_mode", "consensus_match"),
        expected_rcode=entry_data.get("expected_rcode", "NOERROR"),
        expected_answers=list(entry_data.get("expected_answers", [])),
        expected_nameservers=list(entry_data.get("expected_nameservers", [])),
        parent_zone=entry_data.get("parent_zone"),
        nxdomain=bool(entry_data.get("nxdomain", False)),
        label=entry_data.get("label", ""),
        source=entry_data.get("source"),
        stability_score=entry_data.get("stability_score"),
        notes=entry_data.get("notes"),
    )
    baseline_key = data.get("baseline_key")
    return PlainDnsProbeSpec(
        probe_id=data["probe_id"],
        kind=data["kind"],
        candidate_idx=int(data["candidate_idx"]),
        candidate_transport=data["candidate_transport"],
        host=data["host"],
        port=int(data["port"]),
        qname=data["qname"],
        rdtype=data["rdtype"],
        probe_name=data["probe_name"],
        is_nxdomain_probe=bool(data["is_nxdomain_probe"]),
        expected_answers=list(data.get("expected_answers", [])),
        baseline_key=None if baseline_key is None else (baseline_key[0], baseline_key[1]),
        entry=entry,
        capability_name=data.get("capability_name", ""),
    )


async def _probe_capability(
    spec: PlainDnsProbeSpec,
    timeout_s: float,
    baseline_resolvers: list[str],
    baseline_cache: dict[tuple[str, str], list[str]],
    capabilities_config: CapabilitiesConfig,
) -> ProbeResult:
    from resolver_inventory.validate.base import resolve_baseline_answers

    async def _send(
        qname: str,
        rdtype: str,
        *,
        want_dnssec: bool = False,
        ecs: tuple[str, int] | None = None,
    ) -> dns.message.Message:
        options: list[dns.edns.Option] | None = None
        if ecs is not None:
            options = [dns.edns.ECSOption(ecs[0], ecs[1])]
        msg = dns.message.make_query(
            qname,
            dns.rdatatype.from_text(rdtype),
            use_edns=0 if (want_dnssec or ecs is not None) else None,
            want_dnssec=want_dnssec,
            options=options,
        )
        msg.id = 0
        if spec.candidate_transport == "dns-udp":
            resp, _ = await _query_udp(spec.host, spec.port, msg, timeout_s)
        else:
            resp, _ = await _query_tcp(spec.host, spec.port, msg, timeout_s)
        return resp

    async def _baseline(qname: str, rdtype: str) -> list[str]:
        return await resolve_baseline_answers(
            qname, rdtype, baseline_resolvers, timeout_s, baseline_cache
        )

    return await run_capability_check(
        spec.capability_name,
        _send,
        capabilities_config,
        resolve_baseline=_baseline,
    )


async def run_python_plain_dns_batch(
    specs: list[PlainDnsProbeSpec],
    *,
    timeout_s: float,
    baseline_resolvers: list[str],
    baseline_cache: dict[tuple[str, str], list[str]],
    parallelism: int,
    capabilities_config: CapabilitiesConfig | None = None,
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
            elif spec.kind == "capability":
                # A missing config means the caller did not opt in; use a
                # disabled config so checks report "unknown" instead of
                # silently probing the default sentinels.
                result = await _probe_capability(
                    spec,
                    timeout_s,
                    baseline_resolvers,
                    baseline_cache,
                    capabilities_config or CapabilitiesConfig(enabled=False),
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
