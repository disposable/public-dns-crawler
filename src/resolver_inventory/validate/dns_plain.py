"""Plain DNS (UDP and TCP) validator."""

from __future__ import annotations

import time

import dns.asyncquery
import dns.message
import dns.rdatatype

from resolver_inventory.models import Candidate, ProbeResult
from resolver_inventory.util.logging import get_logger
from resolver_inventory.validate.base import fail_probe, ok_probe
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
) -> ProbeResult:
    probe_name = f"{transport}:positive:{entry.label}"
    msg = dns.message.make_query(entry.qname, dns.rdatatype.from_text(entry.rdtype))
    msg.id = 0
    try:
        if transport == "dns-udp":
            resp, ms = await _query_udp(host, port, msg, timeout_s)
        else:
            resp, ms = await _query_tcp(host, port, msg, timeout_s)
    except (TimeoutError, OSError, Exception) as exc:
        return fail_probe(probe_name, f"timeout_or_error:{exc!s:.80}")

    rcode = dns.rcode.to_text(resp.rcode())  # type: ignore[attr-defined]
    if rcode not in ("NOERROR", "NXDOMAIN"):
        return fail_probe(probe_name, f"unexpected_rcode:{rcode}", {"rcode": rcode})
    if rcode == "NXDOMAIN":
        return fail_probe(probe_name, "unexpected_nxdomain", {"rcode": rcode})
    return ok_probe(probe_name, ms, {"rcode": rcode})


async def _probe_nxdomain(
    entry: CorpusEntry,
    host: str,
    port: int,
    transport: str,
    timeout_s: float,
) -> ProbeResult:
    probe_name = f"{transport}:nxdomain:{entry.label}"
    msg = dns.message.make_query(entry.qname, dns.rdatatype.A)
    msg.id = 0
    try:
        if transport == "dns-udp":
            resp, ms = await _query_udp(host, port, msg, timeout_s)
        else:
            resp, ms = await _query_tcp(host, port, msg, timeout_s)
    except (TimeoutError, OSError, Exception) as exc:
        return fail_probe(probe_name, f"timeout_or_error:{exc!s:.80}")

    rcode = dns.rcode.to_text(resp.rcode())  # type: ignore[attr-defined]
    if rcode != "NXDOMAIN":
        return fail_probe(
            probe_name,
            "nxdomain_spoofing",
            {"rcode": rcode, "answers": str(len(resp.answer))},
        )
    return ok_probe(probe_name, ms, {"rcode": rcode})


async def validate_dns_candidate(
    candidate: Candidate,
    corpus: Corpus,
    *,
    timeout_s: float = 2.0,
    rounds: int = 3,
) -> list[ProbeResult]:
    """Run all DNS probes against a plain DNS candidate."""
    transport = candidate.transport
    host = candidate.host
    port = candidate.port
    probes: list[ProbeResult] = []

    for _ in range(rounds):
        for entry in corpus.positive:
            probes.append(await _probe_positive(entry, host, port, transport, timeout_s))
        for entry in corpus.nxdomain:
            probes.append(await _probe_nxdomain(entry, host, port, transport, timeout_s))

    return probes
