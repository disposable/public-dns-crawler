"""HTTP client helpers for DoH requests."""

from __future__ import annotations

import httpx


def build_doh_client(
    *,
    timeout_s: float = 5.0,
    verify: bool | str = True,
) -> httpx.AsyncClient:
    """Return an async httpx client configured for DoH use."""
    return httpx.AsyncClient(
        http2=True,
        timeout=httpx.Timeout(timeout_s),
        verify=verify,
        follow_redirects=False,
        headers={"Accept": "application/dns-message"},
    )
