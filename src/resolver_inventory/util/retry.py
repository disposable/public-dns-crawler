"""Retry helpers for network operations."""

from __future__ import annotations

import time
import urllib.error
import urllib.request

from resolver_inventory.util.logging import get_logger

logger = get_logger(__name__)

DEFAULT_MAX_RETRIES = 3
DEFAULT_BASE_DELAY = 1.0


def fetch_url(
    url: str,
    *,
    timeout: float = 30.0,
    max_retries: int = DEFAULT_MAX_RETRIES,
    base_delay: float = DEFAULT_BASE_DELAY,
) -> bytes:
    """Fetch *url* with retries and exponential backoff.

    Retries on :class:`urllib.error.URLError` and :class:`OSError`.
    After exhausting retries the last exception is re-raised.
    """
    for attempt in range(max_retries + 1):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                return resp.read()
        except (urllib.error.URLError, OSError) as exc:
            if attempt < max_retries:
                delay = base_delay * (2**attempt)
                logger.warning(
                    "Fetch %s failed (attempt %d/%d): %s. Retrying in %.1fs...",
                    url,
                    attempt + 1,
                    max_retries + 1,
                    exc,
                    delay,
                )
                time.sleep(delay)
            else:
                logger.error(
                    "Fetch %s failed after %d attempts: %s",
                    url,
                    max_retries + 1,
                    exc,
                )
                raise exc
    raise RuntimeError("unreachable")  # pragma: no cover
