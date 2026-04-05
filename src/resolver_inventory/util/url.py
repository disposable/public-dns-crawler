"""URL canonicalization helpers."""

from __future__ import annotations

from urllib.parse import SplitResult, urlsplit, urlunsplit


def canonicalize_doh_url(raw: str) -> str:
    """Canonicalize a DoH URL without collapsing meaningful path/query variants.

    Rules:
    - require HTTPS
    - lowercase scheme and host
    - preserve path case
    - preserve query string exactly
    - normalize away default port 443
    - normalize empty path to "/dns-query"
    - keep trailing slash unless the path is just "/"
    """
    raw = raw.strip()
    if not raw:
        return ""

    try:
        parsed = urlsplit(raw)
    except Exception:
        return ""

    if parsed.scheme.lower() != "https":
        return ""
    if parsed.hostname is None:
        return ""

    host = parsed.hostname.lower()
    port = parsed.port
    if ":" in host and not host.startswith("["):
        host_for_netloc = f"[{host}]"
    else:
        host_for_netloc = host

    if port is None or port == 443:
        netloc = host_for_netloc
    else:
        netloc = f"{host_for_netloc}:{port}"

    path = parsed.path or "/dns-query"
    if path == "":
        path = "/dns-query"
    if path != "/" and path.endswith("/") and not parsed.query:
        # A trailing slash on an endpoint path with no query is usually non-semantic.
        path = path.rstrip("/")
        if not path:
            path = "/"

    canonical = SplitResult(
        scheme="https",
        netloc=netloc,
        path=path,
        query=parsed.query,
        fragment="",
    )
    return urlunsplit(canonical)
