"""Source adapter for AdGuard's public DNS providers JSON list."""

from __future__ import annotations

import json
import urllib.request

from resolver_inventory.models import Candidate
from resolver_inventory.sources.base import BaseSource
from resolver_inventory.util.logging import get_logger

logger = get_logger(__name__)

DEFAULT_URL = (
    "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/filter.txt"
)
PROVIDERS_URL = (
    "https://raw.githubusercontent.com/AdguardTeam/KnowledgeBaseDNS/"
    "master/docs/public-dns/text/providers.json"
)


class AdGuardSource(BaseSource):
    """Fetch AdGuard's DNS providers JSON and yield DoH candidates."""

    SOURCE_NAME = "adguard"

    def candidates(self) -> list[Candidate]:
        url = self.entry.url or self.entry.extra.get("url") or PROVIDERS_URL
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception as exc:
            logger.warning("adguard fetch failed: %s", exc)
            return []

        results: list[Candidate] = []
        providers = data if isinstance(data, list) else data.get("providers", [])
        for provider in providers:
            name = provider.get("name") or provider.get("title") or None
            for proto in provider.get("protocols", []):
                if proto.get("type") != "doh":
                    continue
                endpoint_url = proto.get("url", "")
                if not endpoint_url:
                    continue
                host, port, path = _parse_doh_url(endpoint_url)
                bootstrap_ipv4 = list(proto.get("bootstrap_ipv4", []))
                bootstrap_ipv6 = list(proto.get("bootstrap_ipv6", []))
                results.append(
                    Candidate(
                        provider=name,
                        source=self.SOURCE_NAME,
                        transport="doh",
                        endpoint_url=endpoint_url,
                        host=host,
                        port=port,
                        path=path,
                        bootstrap_ipv4=bootstrap_ipv4,
                        bootstrap_ipv6=bootstrap_ipv6,
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
