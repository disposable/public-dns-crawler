"""Shared helpers for validators."""

from __future__ import annotations

from typing import TYPE_CHECKING

import dns.asyncquery
import dns.message
import dns.rdatatype

from resolver_inventory.models import ProbeResult

if TYPE_CHECKING:
    from resolver_inventory.validate.corpus import CorpusEntry


def ok_probe(probe: str, latency_ms: float, details: dict[str, str] | None = None) -> ProbeResult:
    return ProbeResult(ok=True, probe=probe, latency_ms=latency_ms, details=details or {})


def fail_probe(probe: str, error: str, details: dict[str, str] | None = None) -> ProbeResult:
    return ProbeResult(ok=False, probe=probe, error=error, details=details or {})


def render_probe_qname(entry: CorpusEntry) -> str:
    return entry.render_qname()


def normalize_answer_set(message: dns.message.Message, rdtype: str) -> list[str]:
    rdatatype = dns.rdatatype.from_text(rdtype)
    normalized: list[str] = []
    for rrset in message.answer:
        if rrset.rdtype != rdatatype:
            continue
        for record in rrset:
            normalized.append(_normalize_rdata_text(record.to_text(), rdtype))
    return sorted(normalized)


def normalize_expected_answers(answers: list[str], rdtype: str) -> list[str]:
    return sorted(_normalize_rdata_text(answer, rdtype) for answer in answers)


async def resolve_baseline_answers(
    qname: str,
    rdtype: str,
    baseline_resolvers: list[str],
    timeout_s: float,
    baseline_cache: dict[tuple[str, str], list[str]],
) -> list[str]:
    cache_key = (qname, rdtype)
    if cache_key in baseline_cache:
        return baseline_cache[cache_key]

    observed: list[list[str]] = []
    for resolver in baseline_resolvers:
        host, port = parse_resolver_endpoint(resolver)
        msg = dns.message.make_query(qname, dns.rdatatype.from_text(rdtype))
        msg.id = 0
        resp = await dns.asyncquery.udp(msg, host, port=port, timeout=timeout_s)
        observed.append(normalize_answer_set(resp, rdtype))

    first = observed[0] if observed else []
    if not observed or any(answer_set != first for answer_set in observed[1:]):
        raise ValueError(f"baseline consensus mismatch for {qname} {rdtype}")
    baseline_cache[cache_key] = first
    return first


def parse_resolver_endpoint(endpoint: str) -> tuple[str, int]:
    if ":" in endpoint and endpoint.count(":") == 1:
        host, port = endpoint.rsplit(":", 1)
        return host, int(port)
    return endpoint, 53


def _normalize_rdata_text(value: str, rdtype: str) -> str:
    if rdtype in {"NS", "CNAME", "PTR"}:
        return value.rstrip(".").lower() + "."
    return value
