"""Source adapter for AdGuard's public DNS providers markdown list."""

from __future__ import annotations

import ipaddress
import re

from resolver_inventory.models import Candidate
from resolver_inventory.sources.base import BaseSource
from resolver_inventory.util.logging import get_logger
from resolver_inventory.util.retry import fetch_url

logger = get_logger(__name__)

DEFAULT_URL = (
    "https://raw.githubusercontent.com/AdguardTeam/KnowledgeBaseDNS/"
    "master/docs/general/dns-providers.md"
)
PROVIDERS_URL = DEFAULT_URL

_HEADING_RE = re.compile(r"^###\s+(?P<provider>.+?)\s*$")
_DOH_ROW_RE = re.compile(r"^\|\s*DNS-over-HTTPS\s*\|\s*`(?P<url>https://[^`]+)`")
_DNS_ROW_RE = re.compile(r"^\|\s*DNS\s*,\s*(?P<family>IPv4|IPv6)\s*\|")
_BACKTICKED_RE = re.compile(r"`([^`]+)`")


class AdGuardDnsSource(BaseSource):
    """Fetch AdGuard's DNS providers markdown and yield plain DNS candidates.

    Parses the ``DNS, IPv4`` and ``DNS, IPv6`` rows and emits both UDP and TCP
    candidates for each address, mirroring the publicdns.info source.
    """

    SOURCE_NAME = "adguard-dns"

    def candidates(self) -> list[Candidate]:
        url = self.entry.url or self.entry.extra.get("url") or PROVIDERS_URL
        try:
            data = fetch_url(url, timeout=30).decode("utf-8", errors="replace")
        except Exception as exc:
            logger.warning("adguard-dns fetch failed: %s", exc)
            return []

        current_provider: str | None = None
        seen: set[str] = set()
        results: list[Candidate] = []
        for line in data.splitlines():
            stripped = line.strip()
            heading = _HEADING_RE.match(stripped)
            if heading:
                current_provider = heading.group("provider").strip("* ")
                continue

            match = _DNS_ROW_RE.match(stripped)
            if not match:
                continue
            version = 6 if match.group("family") == "IPv6" else 4
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            if len(cells) < 2:
                continue
            for token in _BACKTICKED_RE.findall(cells[1]):
                try:
                    addr = ipaddress.ip_address(token)
                except ValueError:
                    continue
                if addr.version != version or str(addr) in seen:
                    continue
                seen.add(str(addr))
                for transport in ("dns-udp", "dns-tcp"):
                    results.append(
                        Candidate(
                            provider=current_provider,
                            source=self.SOURCE_NAME,
                            transport=transport,  # type: ignore[arg-type]
                            endpoint_url=None,
                            host=str(addr),
                            port=53,
                            path=None,
                        )
                    )
        logger.info("adguard-dns: found %d plain DNS endpoints", len(results))
        return results


class AdGuardSource(BaseSource):
    """Fetch AdGuard's DNS providers markdown and yield DoH candidates."""

    SOURCE_NAME = "adguard"

    def candidates(self) -> list[Candidate]:
        url = self.entry.url or self.entry.extra.get("url") or PROVIDERS_URL
        try:
            data = fetch_url(url, timeout=30).decode("utf-8", errors="replace")
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
    try:
        port = parsed.port or 443
    except ValueError:
        port = 443
    path = parsed.path or "/dns-query"
    return host, port, path
