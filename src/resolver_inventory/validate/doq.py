"""DoQ (DNS-over-QUIC, RFC 9250) validator."""

from __future__ import annotations

import asyncio
import ssl
import time

import dns.asyncquery
import dns.exception
import dns.message
import dns.rcode
import dns.rdatatype

from resolver_inventory.models import Candidate, ProbeResult
from resolver_inventory.util.logging import get_logger
from resolver_inventory.validate.base import (
    fail_probe,
    normalize_answer_set,
    render_probe_qname,
)
from resolver_inventory.validate.corpus import Corpus, CorpusEntry
from resolver_inventory.validate.dns_plain import (
    evaluate_nxdomain_probe_result,
    evaluate_positive_probe_result,
)
from resolver_inventory.validate.dot import (
    _dot_addr_cache_key,
    _resolve_dot_addresses,
)

logger = get_logger(__name__)


async def _query_doq(
    host: str,
    port: int,
    msg: dns.message.Message,
    timeout_s: float,
    server_hostname: str | None,
    *,
    verify: bool | str = True,
) -> tuple[dns.message.Message, float]:
    start = time.perf_counter()
    resp = await dns.asyncquery.quic(
        msg,
        host,
        port=port,
        timeout=timeout_s,
        server_hostname=server_hostname,
        verify=verify,
    )
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return resp, elapsed_ms


async def _query_doq_candidate(
    candidate: Candidate,
    msg: dns.message.Message,
    timeout_s: float,
    addr_cache: dict[str, list[str]] | None,
    addr_locks: dict[str, asyncio.Lock] | None = None,
    *,
    verify: bool | str = True,
) -> tuple[dns.message.Message, float]:
    """Query a DoQ candidate, resolving hostname endpoints to addresses.

    ``where`` must be an IP literal, so hostname candidates go through the
    same bootstrap-aware resolution layer as DoT.
    """
    addresses = await _resolve_dot_addresses(candidate, timeout_s, addr_cache, addr_locks)
    if not addresses:
        raise dns.exception.DNSException(f"cannot resolve DoQ host {candidate.host!r}")
    if addr_cache is not None and len(addresses) > 1:
        cache_key = _dot_addr_cache_key(candidate)
        addr_cache[cache_key] = addresses[1:] + addresses[:1]
    return await _query_doq(
        addresses[0],
        candidate.port,
        msg,
        timeout_s,
        candidate.tls_server_name or candidate.host,
        verify=verify,
    )


def _classify_doq_transport_error(exc: Exception) -> str:
    """Classify QUIC/TLS failures.

    aioquic surfaces certificate and handshake failures through its own
    exception hierarchy (``CryptoError``, QUIC transport errors) rather than
    ``ssl.SSLError``, so match on module/class names in addition to ssl
    exceptions.
    """
    if isinstance(exc, ssl.SSLCertVerificationError):
        text = str(exc).lower()
        if "hostname" in text or "not valid for" in text or "ip address" in text:
            return f"tls_name_mismatch:{exc!s:.80}"
        return f"tls_error:{exc!s:.80}"
    if isinstance(exc, ssl.SSLError):
        return f"tls_error:{exc!s:.80}"
    cls = type(exc)
    module = cls.__module__ or ""
    if "aioquic" in module or cls.__name__ == "CryptoError":
        text = str(exc).lower()
        if "doesn't match" in text or "hostname" in text:
            return f"tls_name_mismatch:{exc!s:.80}"
        if "certificate" in text:
            return f"tls_error:{exc!s:.80}"
        return f"timeout_or_error:{exc!s:.80}"
    return f"timeout_or_error:{exc!s:.80}"


async def _probe_positive_doq(
    entry: CorpusEntry,
    candidate: Candidate,
    timeout_s: float,
    baseline_resolvers: list[str],
    baseline_cache: dict[tuple[str, str], list[str]],
    addr_cache: dict[str, list[str]] | None = None,
    addr_locks: dict[str, asyncio.Lock] | None = None,
    verify: bool | str = True,
) -> ProbeResult:
    probe_name = f"doq:positive:{entry.label}"
    qname = render_probe_qname(entry)
    msg = dns.message.make_query(qname, dns.rdatatype.from_text(entry.rdtype))
    msg.id = 0
    try:
        resp, ms = await _query_doq_candidate(
            candidate,
            msg,
            timeout_s,
            addr_cache,
            addr_locks,
            verify=verify,
        )
    except Exception as exc:
        return fail_probe(probe_name, _classify_doq_transport_error(exc))

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


async def _probe_nxdomain_doq(
    entry: CorpusEntry,
    candidate: Candidate,
    timeout_s: float,
    addr_cache: dict[str, list[str]] | None = None,
    addr_locks: dict[str, asyncio.Lock] | None = None,
    verify: bool | str = True,
) -> ProbeResult:
    probe_name = f"doq:nxdomain:{entry.label}"
    qname = render_probe_qname(entry)
    msg = dns.message.make_query(qname, dns.rdatatype.A)
    msg.id = 0
    try:
        resp, ms = await _query_doq_candidate(
            candidate,
            msg,
            timeout_s,
            addr_cache,
            addr_locks,
            verify=verify,
        )
    except Exception as exc:
        return fail_probe(probe_name, _classify_doq_transport_error(exc))

    rcode = dns.rcode.to_text(resp.rcode())  # type: ignore[attr-defined]
    return evaluate_nxdomain_probe_result(
        probe_name=probe_name,
        qname=qname,
        rcode=rcode,
        answer_count=len(resp.answer),
        latency_ms=ms,
    )


async def validate_doq_candidate(
    candidate: Candidate,
    corpus: Corpus,
    *,
    timeout_s: float = 5.0,
    rounds: int = 3,
    baseline_resolvers: list[str] | None = None,
    baseline_cache: dict[tuple[str, str], list[str]] | None = None,
    verify: bool | str = True,
) -> list[ProbeResult]:
    """Run all DoQ probes against a DoQ candidate.

    Every probe performs a QUIC handshake with certificate validation
    (SNI via ``server_hostname``), so TLS failures surface as
    ``tls_error``/``tls_name_mismatch`` on the failing probes.
    """
    baseline_resolvers = baseline_resolvers or ["1.1.1.1", "9.9.9.9", "8.8.8.8"]
    baseline_cache = baseline_cache or {}
    addr_cache: dict[str, list[str]] = {}
    addr_locks: dict[str, asyncio.Lock] = {}

    coros = []
    for _ in range(rounds):
        for entry in corpus.positive:
            coros.append(
                _probe_positive_doq(
                    entry,
                    candidate,
                    timeout_s,
                    baseline_resolvers,
                    baseline_cache,
                    addr_cache,
                    addr_locks,
                    verify,
                )
            )
        for entry in corpus.nxdomain:
            coros.append(
                _probe_nxdomain_doq(entry, candidate, timeout_s, addr_cache, addr_locks, verify)
            )
    return list(await asyncio.gather(*coros))
