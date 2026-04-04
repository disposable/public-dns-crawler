"""Source adapter for the curl wiki DNS-over-HTTPS provider list."""

from __future__ import annotations

import re
import urllib.request

from resolver_inventory.models import Candidate
from resolver_inventory.sources.base import BaseSource
from resolver_inventory.util.logging import get_logger

logger = get_logger(__name__)

DEFAULT_URL = "https://raw.githubusercontent.com/wiki/curl/curl/DNS-over-HTTPS.md"
PROVIDERS_URL = DEFAULT_URL

_URL_RE = re.compile(r'https://[^\s"\'<>]+/dns-query[^\s"\'<>]*')


class CurlWikiSource(BaseSource):
    """Scrape DoH URLs from curl's DoH providers page."""

    SOURCE_NAME = "curl_wiki"

    def candidates(self) -> list[Candidate]:
        url = self.entry.url or self.entry.extra.get("url") or PROVIDERS_URL
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                html = resp.read().decode("utf-8", errors="replace")
        except Exception as exc:
            logger.warning("curl_wiki fetch failed: %s", exc)
            return []

        seen: set[str] = set()
        results: list[Candidate] = []
        for m in _URL_RE.finditer(html):
            endpoint_url = m.group(0).rstrip(".,;)")
            if endpoint_url in seen:
                continue
            seen.add(endpoint_url)
            host, port, path = _parse_doh_url(endpoint_url)
            results.append(
                Candidate(
                    provider=None,
                    source=self.SOURCE_NAME,
                    transport="doh",
                    endpoint_url=endpoint_url,
                    host=host,
                    port=port,
                    path=path,
                    tls_server_name=host,
                )
            )
        logger.info("curl_wiki: found %d DoH endpoints", len(results))
        return results


def _parse_doh_url(url: str) -> tuple[str, int, str]:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or 443
    path = parsed.path or "/dns-query"
    return host, port, path
