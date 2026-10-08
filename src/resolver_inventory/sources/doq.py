"""Source adapters for DNS-over-QUIC resolver discovery.

Two adapters:
- ``AdGuardDoqSource`` parses ``quic://`` rows from AdGuard's providers
  markdown (including ``Hostname:``-prefixed cells and ``IP:``/``IPv6:``
  bootstrap addresses).
- ``ManualDoqSource`` loads endpoints from a local TOML file.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from urllib.parse import unquote, urlparse

from resolver_inventory.models import Candidate
from resolver_inventory.sources.adguard import PROVIDERS_URL
from resolver_inventory.sources.base import BaseSource
from resolver_inventory.sources.dot import (
    _HEADING_RE,
    _dot_row_cells,
    _ip_fields,
)
from resolver_inventory.util.logging import get_logger
from resolver_inventory.util.retry import fetch_url

logger = get_logger(__name__)

# Rows whose first table cell starts with DNS-over-QUIC.
_DOQ_ROW_RE = re.compile(r"^\|\s*DNS-over-QUIC[^|]*\|")
_QUIC_URL_RE = re.compile(r"`(quic://[^`]+)`")
_HOSTNAME_FIELD_RE = re.compile(r"\bHostname:\s*`([^`]+)`")
_IPV4_FIELD_RE = re.compile(r"\bIP:\s*`([^`]+)`")
_IPV6_FIELD_RE = re.compile(r"\bIPv6:\s*`([^`]+)`")

DEFAULT_DOQ_PORT = 853


class AdGuardDoqSource(BaseSource):
    """Fetch AdGuard's DNS providers markdown and yield DoQ candidates."""

    SOURCE_NAME = "adguard-doq"

    def candidates(self) -> list[Candidate]:
        url = self.entry.url or self.entry.extra.get("url") or PROVIDERS_URL
        try:
            data = fetch_url(url, timeout=30).decode("utf-8", errors="replace")
        except Exception as exc:
            logger.warning("adguard-doq fetch failed: %s", exc)
            return []

        current_provider: str | None = None
        seen: set[tuple[str, int, str]] = set()
        results: list[Candidate] = []
        for line in data.splitlines():
            stripped = line.strip()
            heading = _HEADING_RE.match(stripped)
            if heading:
                current_provider = heading.group("provider").strip("* ")
                continue

            if not _DOQ_ROW_RE.match(stripped):
                continue
            cells = _dot_row_cells(stripped)
            if len(cells) < 2:
                continue
            cell = cells[1]

            urls = _QUIC_URL_RE.findall(cell)
            if not urls:
                host_field = _HOSTNAME_FIELD_RE.search(cell)
                if host_field:
                    name = host_field.group(1)
                    urls = [name if name.startswith("quic://") else f"quic://{name}"]
            bootstrap_ipv4 = _ip_fields(_IPV4_FIELD_RE.findall(cell), 4)
            bootstrap_ipv6 = _ip_fields(_IPV6_FIELD_RE.findall(cell), 6)

            for raw_url in urls:
                endpoint = raw_url.rstrip(".,;)")
                host, port, tls_name = _parse_doq_url(endpoint)
                if not host:
                    continue
                key = (host, port, tls_name or "")
                if key in seen:
                    continue
                seen.add(key)
                results.append(
                    Candidate(
                        provider=current_provider,
                        source=self.SOURCE_NAME,
                        transport="doq",
                        endpoint_url=None,
                        host=host,
                        port=port,
                        path=None,
                        bootstrap_ipv4=list(bootstrap_ipv4),
                        bootstrap_ipv6=list(bootstrap_ipv6),
                        tls_server_name=tls_name or host,
                    )
                )
        logger.info("adguard-doq: found %d DoQ endpoints", len(results))
        return results


class ManualDoqSource(BaseSource):
    """Load DoQ endpoints from a TOML file.

    Expected TOML structure::

        [[endpoints]]
        host = "dns.example.com"
        port = 853
        provider = "Example"
        tls_server_name = "dns.example.com"
        bootstrap_ipv4 = ["1.2.3.4"]
    """

    SOURCE_NAME = "manual-doq"

    def candidates(self) -> list[Candidate]:
        if not self.entry.path:
            return []
        path = Path(self.entry.path)
        if not path.exists():
            return []
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
        raw_list: list[dict[str, object]] = data.get("endpoints", [])
        results: list[Candidate] = []
        for item in raw_list:
            host = str(item.get("host", "")).strip()
            if not host:
                continue
            try:
                port = int(item.get("port", DEFAULT_DOQ_PORT))  # type: ignore[arg-type]
            except (TypeError, ValueError):
                port = DEFAULT_DOQ_PORT
            results.append(
                Candidate(
                    provider=str(item["provider"]) if "provider" in item else None,
                    source=self.SOURCE_NAME,
                    transport="doq",
                    endpoint_url=None,
                    host=host,
                    port=port,
                    path=None,
                    bootstrap_ipv4=[str(x) for x in item.get("bootstrap_ipv4", [])],  # type: ignore[union-attr]
                    bootstrap_ipv6=[str(x) for x in item.get("bootstrap_ipv6", [])],  # type: ignore[union-attr]
                    tls_server_name=(
                        str(item["tls_server_name"]) if "tls_server_name" in item else host
                    ),
                    metadata={
                        k: str(v)
                        for k, v in item.items()
                        if k
                        not in {
                            "host",
                            "port",
                            "provider",
                            "bootstrap_ipv4",
                            "bootstrap_ipv6",
                            "tls_server_name",
                        }
                    },
                )
            )
        return results


def _parse_doq_url(url: str) -> tuple[str, int, str | None]:
    """Extract (host, port, tls_name) from a quic:// DoQ URL.

    A ``#name`` fragment carries the TLS authentication name for IP-literal
    endpoints (``quic://9.9.9.9#dns.quad9.net``), matching the tls://
    convention.

    Returns ``("", 0, None)`` for malformed URLs so callers skip the row;
    urlparse raises on unbalanced IPv6 brackets and invalid ports.
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or DEFAULT_DOQ_PORT
    except ValueError:
        return "", 0, None
    tls_name = unquote(parsed.fragment).strip() if parsed.fragment else None
    return host, port, tls_name
