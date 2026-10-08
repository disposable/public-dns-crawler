"""Normalization for DoQ (DNS-over-QUIC) candidates."""

from __future__ import annotations

from resolver_inventory.models import Candidate, FilteredCandidate
from resolver_inventory.normalize.dot import (
    _is_hostname,
    _is_hostname_or_ip,
    _normalize_dot_host,
    _valid_bootstrap,
)


def normalize_doq_candidates(
    candidates: list[Candidate],
    *,
    filtered: list[FilteredCandidate] | None = None,
) -> list[Candidate]:
    """Deduplicate and validate DoQ candidates.

    Same rules as DoT: the host may be a hostname (required for TLS
    verification) or an IP address; ``tls_server_name`` defaults to the host
    when it is a hostname.
    """
    seen: set[tuple[str, int, str]] = set()
    result: list[Candidate] = []
    for c in candidates:
        if c.transport != "doq":
            continue
        host = _normalize_dot_host(c.host)
        port = c.port or 853
        if (
            not host
            or port <= 0
            or port > 65535
            or not _valid_bootstrap(c.bootstrap_ipv4, 4)
            or not _valid_bootstrap(c.bootstrap_ipv6, 6)
        ):
            if filtered is not None:
                filtered.append(
                    FilteredCandidate(
                        candidate=c,
                        reason="invalid_doq_endpoint",
                        detail=f"DoQ endpoint {c.host!r}:{c.port} is not valid",
                        stage="normalize",
                    )
                )
            continue
        tls_server_name = (c.tls_server_name or "").strip().rstrip(".").lower() or (
            host if _is_hostname(host) else None
        )
        # An explicit auth name must itself be a valid hostname or IP literal.
        if c.tls_server_name and not (tls_server_name and _is_hostname_or_ip(tls_server_name)):
            if filtered is not None:
                filtered.append(
                    FilteredCandidate(
                        candidate=c,
                        reason="invalid_doq_endpoint",
                        detail=f"DoQ tls_server_name {c.tls_server_name!r} is not valid",
                        stage="normalize",
                    )
                )
            continue
        # Dedup on the effective TLS name so an explicit name equal to the
        # host collapses with the implicit default - matching the resolver
        # key granularity used for history rows.
        key = (host, port, tls_server_name or host)
        if key in seen:
            if filtered is not None:
                filtered.append(
                    FilteredCandidate(
                        candidate=c,
                        reason="duplicate_doq_candidate",
                        detail=f"duplicate DoQ endpoint {host}:{port}",
                        stage="normalize",
                    )
                )
            continue
        seen.add(key)
        result.append(
            Candidate(
                provider=c.provider,
                source=c.source,
                transport="doq",
                endpoint_url=None,
                host=host,
                port=port,
                path=None,
                bootstrap_ipv4=list(c.bootstrap_ipv4),
                bootstrap_ipv6=list(c.bootstrap_ipv6),
                tls_server_name=tls_server_name,
                metadata=dict(c.metadata),
            )
        )
    return result
