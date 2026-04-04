"""DoH (DNS-over-HTTPS) validator."""

from __future__ import annotations

import ssl
import time

import dns.message
import dns.rdatatype
import httpx

from resolver_inventory.models import Candidate, ProbeResult
from resolver_inventory.util.logging import get_logger
from resolver_inventory.validate.base import fail_probe, ok_probe
from resolver_inventory.validate.corpus import Corpus, CorpusEntry

logger = get_logger(__name__)

DOH_CONTENT_TYPE = "application/dns-message"


def _build_wire(qname: str, rdtype: str) -> bytes:
    msg = dns.message.make_query(qname, dns.rdatatype.from_text(rdtype))
    msg.id = 0
    return msg.to_wire()


async def _doh_post(
    client: httpx.AsyncClient,
    url: str,
    wire: bytes,
) -> tuple[dns.message.Message, float]:
    start = time.perf_counter()
    resp = await client.post(
        url,
        content=wire,
        headers={"Content-Type": DOH_CONTENT_TYPE},
    )
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    resp.raise_for_status()
    msg = dns.message.from_wire(resp.content)
    return msg, elapsed_ms


async def _probe_positive_doh(
    entry: CorpusEntry,
    client: httpx.AsyncClient,
    url: str,
) -> ProbeResult:
    probe_name = f"doh:positive:{entry.label}"
    wire = _build_wire(entry.qname, entry.rdtype)
    try:
        resp_msg, ms = await _doh_post(client, url, wire)
    except httpx.TimeoutException as exc:
        return fail_probe(probe_name, f"timeout:{exc!s:.80}")
    except httpx.HTTPStatusError as exc:
        return fail_probe(probe_name, f"http_error:{exc.response.status_code}")
    except ssl.SSLError as exc:
        return fail_probe(probe_name, f"tls_error:{exc!s:.80}")
    except Exception as exc:
        return fail_probe(probe_name, f"error:{exc!s:.80}")

    rcode = dns.rcode.to_text(resp_msg.rcode())  # type: ignore[attr-defined]
    if rcode == "NXDOMAIN":
        return fail_probe(probe_name, "unexpected_nxdomain", {"rcode": rcode})
    if rcode != "NOERROR":
        return fail_probe(probe_name, f"unexpected_rcode:{rcode}", {"rcode": rcode})
    return ok_probe(probe_name, ms, {"rcode": rcode})


async def _probe_nxdomain_doh(
    entry: CorpusEntry,
    client: httpx.AsyncClient,
    url: str,
) -> ProbeResult:
    probe_name = f"doh:nxdomain:{entry.label}"
    wire = _build_wire(entry.qname, "A")
    try:
        resp_msg, ms = await _doh_post(client, url, wire)
    except httpx.TimeoutException as exc:
        return fail_probe(probe_name, f"timeout:{exc!s:.80}")
    except httpx.HTTPStatusError as exc:
        return fail_probe(probe_name, f"http_error:{exc.response.status_code}")
    except ssl.SSLError as exc:
        return fail_probe(probe_name, f"tls_error:{exc!s:.80}")
    except Exception as exc:
        return fail_probe(probe_name, f"error:{exc!s:.80}")

    rcode = dns.rcode.to_text(resp_msg.rcode())  # type: ignore[attr-defined]
    if rcode != "NXDOMAIN":
        return fail_probe(probe_name, "nxdomain_spoofing", {"rcode": rcode})
    return ok_probe(probe_name, ms, {"rcode": rcode})


async def _probe_tls(
    candidate: Candidate,
    timeout_s: float,
    ssl_context: ssl.SSLContext | None = None,
) -> ProbeResult:
    """Check that the TLS certificate matches the expected server name."""
    probe_name = "doh:tls"
    url = candidate.endpoint_url or ""
    sni = candidate.tls_server_name or candidate.host
    verify: bool | ssl.SSLContext = ssl_context if ssl_context is not None else True
    try:
        async with httpx.AsyncClient(
            http2=True,
            timeout=httpx.Timeout(timeout_s),
            verify=verify,
        ) as client:
            start = time.perf_counter()
            await client.head(url)
            ms = (time.perf_counter() - start) * 1000.0
        return ok_probe(probe_name, ms, {"sni": sni})
    except httpx.ConnectError as exc:
        err = str(exc)
        if "ssl" in err.lower() or "certificate" in err.lower():
            return fail_probe(probe_name, f"tls_name_mismatch:{err:.80}", {"sni": sni})
        return fail_probe(probe_name, f"connect_error:{err:.80}", {"sni": sni})
    except Exception as exc:
        return fail_probe(probe_name, f"error:{exc!s:.80}", {"sni": sni})


async def validate_doh_candidate(
    candidate: Candidate,
    corpus: Corpus,
    *,
    timeout_s: float = 5.0,
    rounds: int = 3,
    ssl_context: ssl.SSLContext | None = None,
) -> list[ProbeResult]:
    """Run all DoH probes against a DoH candidate."""
    url = candidate.endpoint_url or ""
    probes: list[ProbeResult] = []

    verify: bool | ssl.SSLContext = ssl_context if ssl_context is not None else True

    probes.append(await _probe_tls(candidate, timeout_s, ssl_context))

    async with httpx.AsyncClient(
        http2=True,
        timeout=httpx.Timeout(timeout_s),
        verify=verify,
        follow_redirects=False,
        headers={"Accept": DOH_CONTENT_TYPE},
    ) as client:
        for _ in range(rounds):
            for entry in corpus.positive:
                probes.append(await _probe_positive_doh(entry, client, url))
            for entry in corpus.nxdomain:
                probes.append(await _probe_nxdomain_doh(entry, client, url))

    return probes
