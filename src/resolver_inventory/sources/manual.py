"""Manual seed source adapters for plain DNS and DoH endpoints."""

from __future__ import annotations

import tomllib
from pathlib import Path

from resolver_inventory.models import Candidate
from resolver_inventory.sources.base import BaseSource


class ManualDnsSource(BaseSource):
    """Load plain DNS resolver IPs from a text file (one IP per line)."""

    SOURCE_NAME = "manual-dns"

    def candidates(self) -> list[Candidate]:
        if not self.entry.path:
            return []
        path = Path(self.entry.path)
        if not path.exists():
            return []
        results: list[Candidate] = []
        for raw_line in path.read_text().splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            host, _, port_str = line.partition(":")
            port = int(port_str) if port_str else 53
            for transport in ("dns-udp", "dns-tcp"):
                results.append(
                    Candidate(
                        provider=None,
                        source=self.SOURCE_NAME,
                        transport=transport,  # type: ignore[arg-type]
                        endpoint_url=None,
                        host=host.strip(),
                        port=port,
                        path=None,
                    )
                )
        return results


class ManualDohSource(BaseSource):
    """Load DoH endpoints from a TOML file.

    Expected TOML structure::

        [[endpoints]]
        url = "https://dns.example.com/dns-query"
        provider = "Example"
        bootstrap_ipv4 = ["1.2.3.4"]
        tls_server_name = "dns.example.com"
    """

    SOURCE_NAME = "manual-doh"

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
            url: str = str(item.get("url", ""))
            if not url:
                continue
            host, port, path_part = _parse_doh_url(url)
            results.append(
                Candidate(
                    provider=str(item["provider"]) if "provider" in item else None,
                    source=self.SOURCE_NAME,
                    transport="doh",
                    endpoint_url=url,
                    host=host,
                    port=port,
                    path=path_part,
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
                            "url",
                            "provider",
                            "bootstrap_ipv4",
                            "bootstrap_ipv6",
                            "tls_server_name",
                        }
                    },
                )
            )
        return results


def _parse_doh_url(url: str) -> tuple[str, int, str]:
    """Extract (host, port, path) from a DoH URL."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/dns-query"
    return host, port, path
