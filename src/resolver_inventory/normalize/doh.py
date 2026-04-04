"""Normalization for DoH candidates."""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse

from resolver_inventory.models import Candidate, FilteredCandidate


def normalize_doh_candidates(
    candidates: list[Candidate],
    *,
    filtered: list[FilteredCandidate] | None = None,
) -> list[Candidate]:
    """Deduplicate and validate DoH candidates."""
    seen: set[str] = set()
    result: list[Candidate] = []
    for c in candidates:
        if c.transport != "doh":
            continue
        url = _normalize_url(c.endpoint_url or "")
        if not url:
            if filtered is not None:
                filtered.append(
                    FilteredCandidate(
                        candidate=c,
                        reason="invalid_doh_url",
                        detail=(
                            f"endpoint URL {c.endpoint_url or ''!r} is not a valid HTTPS DoH URL"
                        ),
                        stage="normalize",
                    )
                )
            continue
        if url in seen:
            if filtered is not None:
                filtered.append(
                    FilteredCandidate(
                        candidate=c,
                        reason="duplicate_doh_candidate",
                        detail=f"duplicate DoH endpoint {url}",
                        stage="normalize",
                    )
                )
            continue
        seen.add(url)
        parsed = urlparse(url)
        host = parsed.hostname or c.host
        port = parsed.port or 443
        path = parsed.path or "/dns-query"
        result.append(
            Candidate(
                provider=c.provider,
                source=c.source,
                transport="doh",
                endpoint_url=url,
                host=host,
                port=port,
                path=path,
                bootstrap_ipv4=list(c.bootstrap_ipv4),
                bootstrap_ipv6=list(c.bootstrap_ipv6),
                tls_server_name=c.tls_server_name or host,
                metadata=dict(c.metadata),
            )
        )
    return result


def _normalize_url(raw: str) -> str:
    """Normalize a DoH URL to a canonical form."""
    raw = raw.strip()
    if not raw.startswith("https://"):
        return ""
    try:
        p = urlparse(raw)
        if not p.hostname:
            return ""
        normalized = urlunparse(
            (
                p.scheme,
                p.netloc.lower(),
                p.path or "/dns-query",
                "",
                "",
                "",
            )
        )
        return normalized
    except Exception:
        return ""
