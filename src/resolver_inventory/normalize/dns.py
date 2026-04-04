"""Normalization for plain DNS candidates."""

from __future__ import annotations

import ipaddress

from resolver_inventory.models import Candidate, FilteredCandidate


def normalize_dns_candidates(
    candidates: list[Candidate],
    *,
    filtered: list[FilteredCandidate] | None = None,
) -> list[Candidate]:
    """Deduplicate and validate plain DNS candidates."""
    seen: set[tuple[str, int, str]] = set()
    result: list[Candidate] = []
    for c in candidates:
        if c.transport not in ("dns-udp", "dns-tcp"):
            continue
        host = _normalize_host(c.host)
        if not host:
            if filtered is not None:
                filtered.append(
                    FilteredCandidate(
                        candidate=c,
                        reason="invalid_dns_host",
                        detail=f"host {c.host!r} is not a valid IP address",
                        stage="normalize",
                    )
                )
            continue
        key = (host, c.port, c.transport)
        if key in seen:
            if filtered is not None:
                filtered.append(
                    FilteredCandidate(
                        candidate=c,
                        reason="duplicate_dns_candidate",
                        detail=f"duplicate DNS endpoint {host}:{c.port} for transport {c.transport}",
                        stage="normalize",
                    )
                )
            continue
        seen.add(key)
        result.append(
            Candidate(
                provider=c.provider,
                source=c.source,
                transport=c.transport,
                endpoint_url=None,
                host=host,
                port=c.port,
                path=None,
                bootstrap_ipv4=list(c.bootstrap_ipv4),
                bootstrap_ipv6=list(c.bootstrap_ipv6),
                tls_server_name=None,
                metadata=dict(c.metadata),
            )
        )
    return result


def _normalize_host(raw: str) -> str:
    """Validate and normalize an IP address string."""
    raw = raw.strip()
    try:
        addr = ipaddress.ip_address(raw)
        return str(addr)
    except ValueError:
        return ""
