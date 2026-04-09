"""Plain DNS (UDP and TCP) validator."""

from __future__ import annotations

import asyncio
import time

import dns.asyncquery
import dns.message
import dns.rdatatype

from resolver_inventory.models import Candidate, ProbeResult
from resolver_inventory.util.logging import get_logger
from resolver_inventory.validate.base import (
    fail_probe,
    normalize_answer_set,
    normalize_expected_answers,
    ok_probe,
    render_probe_qname,
    resolve_baseline_answers,
)
from resolver_inventory.validate.corpus import Corpus, CorpusEntry

logger = get_logger(__name__)


async def _query_udp(
    host: str,
    port: int,
    msg: dns.message.Message,
    timeout_s: float,
) -> tuple[dns.message.Message, float]:
    start = time.perf_counter()
    resp = await dns.asyncquery.udp(msg, host, port=port, timeout=timeout_s)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return resp, elapsed_ms


async def _query_tcp(
    host: str,
    port: int,
    msg: dns.message.Message,
    timeout_s: float,
) -> tuple[dns.message.Message, float]:
    start = time.perf_counter()
    resp = await dns.asyncquery.tcp(msg, host, port=port, timeout=timeout_s)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return resp, elapsed_ms


async def _probe_positive(
    entry: CorpusEntry,
    host: str,
    port: int,
    transport: str,
    timeout_s: float,
    baseline_resolvers: list[str],
    baseline_cache: dict[tuple[str, str], list[str]],
) -> ProbeResult:
    probe_name = f"{transport}:positive:{entry.label}"
    qname = render_probe_qname(entry)
    msg = dns.message.make_query(qname, dns.rdatatype.from_text(entry.rdtype))
    msg.id = 0
    try:
        if transport == "dns-udp":
            resp, ms = await _query_udp(host, port, msg, timeout_s)
        else:
            resp, ms = await _query_tcp(host, port, msg, timeout_s)
    except (TimeoutError, OSError, Exception) as exc:
        return fail_probe(probe_name, f"timeout_or_error:{exc!s:.80}")

    rcode = dns.rcode.to_text(resp.rcode())  # type: ignore[attr-defined]
    answers = normalize_answer_set(resp, entry.rdtype)
    return await evaluate_positive_probe_result(
        entry,
        probe_name=probe_name,
        qname=qname,
        rcode=rcode,
        answers=answers,
        latency_ms=ms,
        timeout_s=timeout_s,
        baseline_resolvers=baseline_resolvers,
        baseline_cache=baseline_cache,
    )


async def _probe_nxdomain(
    entry: CorpusEntry,
    host: str,
    port: int,
    transport: str,
    timeout_s: float,
) -> ProbeResult:
    probe_name = f"{transport}:nxdomain:{entry.label}"
    qname = render_probe_qname(entry)
    msg = dns.message.make_query(qname, dns.rdatatype.A)
    msg.id = 0
    try:
        if transport == "dns-udp":
            resp, ms = await _query_udp(host, port, msg, timeout_s)
        else:
            resp, ms = await _query_tcp(host, port, msg, timeout_s)
    except (TimeoutError, OSError, Exception) as exc:
        return fail_probe(probe_name, f"timeout_or_error:{exc!s:.80}")

    rcode = dns.rcode.to_text(resp.rcode())  # type: ignore[attr-defined]
    return evaluate_nxdomain_probe_result(
        probe_name=probe_name,
        qname=qname,
        rcode=rcode,
        answer_count=len(resp.answer),
        latency_ms=ms,
    )


async def evaluate_positive_probe_result(
    entry: CorpusEntry,
    *,
    probe_name: str,
    qname: str,
    rcode: str,
    answers: list[str],
    latency_ms: float | None,
    timeout_s: float,
    baseline_resolvers: list[str],
    baseline_cache: dict[tuple[str, str], list[str]],
) -> ProbeResult:
    if rcode not in ("NOERROR", "NXDOMAIN"):
        return fail_probe(probe_name, f"unexpected_rcode:{rcode}", {"rcode": rcode})
    if rcode == "NXDOMAIN":
        return fail_probe(probe_name, "unexpected_nxdomain", {"rcode": rcode})
    if entry.expected_mode == "exact_rrset":
        expected = normalize_expected_answers(entry.expected_answers, entry.rdtype)
        if answers != expected:
            return fail_probe(
                probe_name,
                "answer_mismatch",
                {"expected": ",".join(expected), "actual": ",".join(answers)},
            )
    elif entry.expected_mode == "consensus_match":
        try:
            baseline = await resolve_baseline_answers(
                qname,
                entry.rdtype,
                baseline_resolvers,
                timeout_s,
                baseline_cache,
            )
        except Exception as exc:
            return fail_probe(probe_name, f"baseline_error:{exc!s:.80}")
        if answers != baseline:
            return fail_probe(
                probe_name,
                "answer_mismatch",
                {"expected": ",".join(baseline), "actual": ",".join(answers)},
            )
    details = {"rcode": rcode}
    if latency_ms is None:
        return ProbeResult(ok=True, probe=probe_name, latency_ms=None, details=details)
    return ok_probe(probe_name, latency_ms, details)


def evaluate_nxdomain_probe_result(
    *,
    probe_name: str,
    qname: str,
    rcode: str,
    answer_count: int,
    latency_ms: float | None,
) -> ProbeResult:
    if rcode != "NXDOMAIN":
        return fail_probe(
            probe_name,
            "nxdomain_spoofing",
            {"rcode": rcode, "answers": str(answer_count), "qname": qname},
        )
    details = {"rcode": rcode}
    if latency_ms is None:
        return ProbeResult(ok=True, probe=probe_name, latency_ms=None, details=details)
    return ok_probe(probe_name, latency_ms, details)


async def validate_dns_candidate(
    candidate: Candidate,
    corpus: Corpus,
    *,
    timeout_s: float = 2.0,
    rounds: int = 3,
    baseline_resolvers: list[str] | None = None,
    baseline_cache: dict[tuple[str, str], list[str]] | None = None,
) -> list[ProbeResult]:
    """Run all DNS probes against a plain DNS candidate."""
    transport = candidate.transport
    host = candidate.host
    port = candidate.port
    baseline_resolvers = baseline_resolvers or ["1.1.1.1", "9.9.9.9", "8.8.8.8"]
    baseline_cache = baseline_cache or {}

    coros = []
    for _ in range(rounds):
        for entry in corpus.positive:
            coros.append(
                _probe_positive(
                    entry,
                    host,
                    port,
                    transport,
                    timeout_s,
                    baseline_resolvers,
                    baseline_cache,
                )
            )
        for entry in corpus.nxdomain:
            coros.append(_probe_nxdomain(entry, host, port, transport, timeout_s))
    return list(await asyncio.gather(*coros))
