"""DoT (DNS-over-TLS) validator."""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
import time

import dns.asyncquery
import dns.asyncresolver
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

logger = get_logger(__name__)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _dot_addr_cache_key(candidate: Candidate) -> str:
    """Cache key scoped by bootstrap list so pinned and unpinned entries
    for the same hostname do not share resolution results."""
    return "|".join([candidate.host, *candidate.bootstrap_ipv4, *candidate.bootstrap_ipv6])


async def _resolve_dot_addresses(
    candidate: Candidate,
    timeout_s: float,
    addr_cache: dict[str, list[str]] | None,
    addr_locks: dict[str, asyncio.Lock] | None = None,
) -> list[str]:
    """Return connect addresses for a DoT candidate.

    Bootstrap addresses from the candidate take precedence; otherwise the
    hostname is resolved once through the system resolver. Results are
    cached so per-probe latency measurements exclude DNS resolution time,
    and the cache order is rotated by the caller for address coverage.
    ``addr_locks`` serializes cold-miss resolutions so concurrent probes for
    the same host do not stampede the resolver.
    """
    host = candidate.host
    if _is_ip_literal(host):
        return [host]
    cache_key = _dot_addr_cache_key(candidate)
    if addr_cache is not None and cache_key in addr_cache:
        return addr_cache[cache_key]

    if addr_locks is None:
        return await _resolve_dot_addresses_uncached(candidate, timeout_s, addr_cache)

    lock = addr_locks.setdefault(cache_key, asyncio.Lock())
    async with lock:
        if addr_cache is not None and cache_key in addr_cache:
            return addr_cache[cache_key]
        return await _resolve_dot_addresses_uncached(candidate, timeout_s, addr_cache)


async def _resolve_dot_addresses_uncached(
    candidate: Candidate,
    timeout_s: float,
    addr_cache: dict[str, list[str]] | None,
) -> list[str]:
    addresses = list(candidate.bootstrap_ipv4) + list(candidate.bootstrap_ipv6)
    if not addresses:
        resolver = dns.asyncresolver.Resolver()
        for rdtype in ("A", "AAAA"):
            try:
                answer = await resolver.resolve(candidate.host, rdtype, lifetime=timeout_s)
                addresses.extend(rdata.address for rdata in answer)
            except Exception:
                continue
    if addr_cache is not None:
        addr_cache[_dot_addr_cache_key(candidate)] = addresses
    return addresses


async def _query_dot(
    host: str,
    port: int,
    msg: dns.message.Message,
    timeout_s: float,
    server_hostname: str | None,
    *,
    ssl_context: ssl.SSLContext | None = None,
) -> tuple[dns.message.Message, float]:
    start = time.perf_counter()
    kwargs: dict = {"verify": True}
    if ssl_context is not None:
        kwargs = {"ssl_context": ssl_context}
    resp = await dns.asyncquery.tls(
        msg,
        host,
        port=port,
        timeout=timeout_s,
        server_hostname=server_hostname,
        **kwargs,
    )
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return resp, elapsed_ms


async def _query_dot_candidate(
    candidate: Candidate,
    msg: dns.message.Message,
    timeout_s: float,
    addr_cache: dict[str, list[str]] | None,
    addr_locks: dict[str, asyncio.Lock] | None = None,
    *,
    ssl_context: ssl.SSLContext | None = None,
) -> tuple[dns.message.Message, float]:
    """Query a DoT candidate, resolving hostname endpoints to addresses."""
    addresses = await _resolve_dot_addresses(candidate, timeout_s, addr_cache, addr_locks)
    if not addresses:
        raise dns.exception.DNSException(f"cannot resolve DoT host {candidate.host!r}")
    # Rotate through resolved addresses across calls for coverage.
    if addr_cache is not None and len(addresses) > 1:
        cache_key = _dot_addr_cache_key(candidate)
        addr_cache[cache_key] = addresses[1:] + addresses[:1]
    # Passing the IP literal as server_hostname enables IP-SAN verification,
    # which real DoT endpoints (e.g. tls://1.1.1.1) are expected to carry.
    return await _query_dot(
        addresses[0],
        candidate.port,
        msg,
        timeout_s,
        candidate.tls_server_name or candidate.host,
        ssl_context=ssl_context,
    )


def _classify_dot_transport_error(exc: Exception) -> str:
    if isinstance(exc, ssl.SSLCertVerificationError):
        text = str(exc).lower()
        if "hostname" in text or "not valid for" in text or "ip address" in text:
            return f"tls_name_mismatch:{exc!s:.80}"
        return f"tls_error:{exc!s:.80}"
    if isinstance(exc, ssl.SSLError):
        return f"tls_error:{exc!s:.80}"
    return f"timeout_or_error:{exc!s:.80}"


async def _probe_positive_dot(
    entry: CorpusEntry,
    candidate: Candidate,
    timeout_s: float,
    baseline_resolvers: list[str],
    baseline_cache: dict[tuple[str, str], list[str]],
    addr_cache: dict[str, list[str]] | None = None,
    addr_locks: dict[str, asyncio.Lock] | None = None,
    ssl_context: ssl.SSLContext | None = None,
) -> ProbeResult:
    probe_name = f"dot:positive:{entry.label}"
    qname = render_probe_qname(entry)
    msg = dns.message.make_query(qname, dns.rdatatype.from_text(entry.rdtype))
    msg.id = 0
    try:
        resp, ms = await _query_dot_candidate(
            candidate,
            msg,
            timeout_s,
            addr_cache,
            addr_locks,
            ssl_context=ssl_context,
        )
    except Exception as exc:
        return fail_probe(probe_name, _classify_dot_transport_error(exc))

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


async def _probe_nxdomain_dot(
    entry: CorpusEntry,
    candidate: Candidate,
    timeout_s: float,
    addr_cache: dict[str, list[str]] | None = None,
    addr_locks: dict[str, asyncio.Lock] | None = None,
    ssl_context: ssl.SSLContext | None = None,
) -> ProbeResult:
    probe_name = f"dot:nxdomain:{entry.label}"
    qname = render_probe_qname(entry)
    msg = dns.message.make_query(qname, dns.rdatatype.A)
    msg.id = 0
    try:
        resp, ms = await _query_dot_candidate(
            candidate,
            msg,
            timeout_s,
            addr_cache,
            addr_locks,
            ssl_context=ssl_context,
        )
    except Exception as exc:
        return fail_probe(probe_name, _classify_dot_transport_error(exc))

    rcode = dns.rcode.to_text(resp.rcode())  # type: ignore[attr-defined]
    return evaluate_nxdomain_probe_result(
        probe_name=probe_name,
        qname=qname,
        rcode=rcode,
        answer_count=len(resp.answer),
        latency_ms=ms,
    )


async def validate_dot_candidate(
    candidate: Candidate,
    corpus: Corpus,
    *,
    timeout_s: float = 5.0,
    rounds: int = 3,
    baseline_resolvers: list[str] | None = None,
    baseline_cache: dict[tuple[str, str], list[str]] | None = None,
    ssl_context: ssl.SSLContext | None = None,
) -> list[ProbeResult]:
    """Run all DoT probes against a DoT candidate.

    Every probe performs a TLS handshake (SNI + certificate validation via
    ``server_hostname``), so TLS failures surface as
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
                _probe_positive_dot(
                    entry,
                    candidate,
                    timeout_s,
                    baseline_resolvers,
                    baseline_cache,
                    addr_cache,
                    addr_locks,
                    ssl_context,
                )
            )
        for entry in corpus.nxdomain:
            coros.append(
                _probe_nxdomain_dot(
                    entry, candidate, timeout_s, addr_cache, addr_locks, ssl_context
                )
            )
    return list(await asyncio.gather(*coros))
