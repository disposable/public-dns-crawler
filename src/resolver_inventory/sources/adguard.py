"""Source adapter for AdGuard's public DNS providers markdown list."""

from __future__ import annotations

import re
import urllib.request

from resolver_inventory.models import Candidate
from resolver_inventory.sources.base import BaseSource
from resolver_inventory.util.logging import get_logger

logger = get_logger(__name__)

DEFAULT_URL = (
    "https://raw.githubusercontent.com/AdguardTeam/KnowledgeBaseDNS/"
    "master/docs/general/dns-providers.md"
)
PROVIDERS_URL = DEFAULT_URL

_HEADING_RE = re.compile(r"^###\s+(?P<provider>.+?)\s*$")
_DOH_ROW_RE = re.compile(r"^\|\s*DNS-over-HTTPS\s*\|\s*`(?P<url>https://[^`]+)`")


class AdGuardSource(BaseSource):
    """Fetch AdGuard's DNS providers markdown and yield DoH candidates."""

    SOURCE_NAME = "adguard"

    def candidates(self) -> list[Candidate]:
        url = self.entry.url or self.entry.extra.get("url") or PROVIDERS_URL
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                data = resp.read().decode("utf-8", errors="replace")
        except Exception as exc:
            logger.warning("adguard fetch failed: %s", exc)
            return []

        current_provider: str | None = None
        seen: set[str] = set()
        results: list[Candidate] = []
        for line in data.splitlines():
            heading = _HEADING_RE.match(line.strip())
            if heading:
                current_provider = heading.group("provider").strip("* ")
                continue

            match = _DOH_ROW_RE.match(line.strip())
            if not match:
                continue

            endpoint_url = match.group("url").rstrip(".,;)")
            if endpoint_url in seen:
                continue
            seen.add(endpoint_url)
            host, port, path = _parse_doh_url(endpoint_url)
            results.append(
                Candidate(
                    provider=current_provider,
                    source=self.SOURCE_NAME,
                    transport="doh",
                    endpoint_url=endpoint_url,
                    host=host,
                    port=port,
                    path=path,
                    tls_server_name=host,
                )
            )
        logger.info("adguard: found %d DoH endpoints", len(results))
        return results


def _parse_doh_url(url: str) -> tuple[str, int, str]:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or 443
    path = parsed.path or "/dns-query"
    return host, port, path
