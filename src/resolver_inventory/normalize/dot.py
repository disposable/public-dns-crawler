"""Normalization for DoT (DNS-over-TLS) candidates."""

from __future__ import annotations

import ipaddress
import re

from resolver_inventory.models import Candidate, FilteredCandidate

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\.?$"
)


def normalize_dot_candidates(
    candidates: list[Candidate],
    *,
    filtered: list[FilteredCandidate] | None = None,
) -> list[Candidate]:
    """Deduplicate and validate DoT candidates.

    Unlike plain DNS, the host may be a hostname (required for TLS
    verification of endpoints like ``tls://dns.example.com``) or an IP
    address. ``tls_server_name`` defaults to the host when it is a hostname.
    """
    seen: set[tuple[str, int, str]] = set()
    result: list[Candidate] = []
    for c in candidates:
        if c.transport != "dot":
            continue
        host = _normalize_dot_host(c.host)
        port = c.port or 853
        if not host or port <= 0 or port > 65535:
            if filtered is not None:
                filtered.append(
                    FilteredCandidate(
                        candidate=c,
                        reason="invalid_dot_endpoint",
                        detail=f"DoT endpoint {c.host!r}:{c.port} is not valid",
                        stage="normalize",
                    )
                )
            continue
        tls_server_name = (c.tls_server_name or "").strip() or (
            host if _is_hostname(host) else None
        )
        key = (host, port, tls_server_name or "")
        if key in seen:
            if filtered is not None:
                filtered.append(
                    FilteredCandidate(
                        candidate=c,
                        reason="duplicate_dot_candidate",
                        detail=f"duplicate DoT endpoint {host}:{port}",
                        stage="normalize",
                    )
                )
            continue
        seen.add(key)
        result.append(
            Candidate(
                provider=c.provider,
                source=c.source,
                transport="dot",
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


def _is_hostname(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return bool(_HOSTNAME_RE.match(host))


def _normalize_dot_host(raw: str) -> str:
    """Normalize an IP address or hostname; empty string when invalid."""
    raw = raw.strip().rstrip(".") if raw else ""
    if not raw:
        return ""
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return raw.lower() if _HOSTNAME_RE.match(raw) else ""
