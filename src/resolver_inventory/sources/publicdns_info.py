"""Source adapter for public-dns.info nameserver list."""

from __future__ import annotations

import csv
import io
import urllib.request

from resolver_inventory.models import Candidate
from resolver_inventory.sources.base import BaseSource
from resolver_inventory.util.logging import get_logger

logger = get_logger(__name__)

DEFAULT_URL = "https://public-dns.info/nameservers.csv"


class PublicDnsInfoSource(BaseSource):
    """Fetch the public-dns.info CSV and yield DNS candidates."""

    SOURCE_NAME = "publicdns_info"

    def candidates(self) -> list[Candidate]:
        url = self.entry.url or self.entry.extra.get("url") or DEFAULT_URL
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                content = resp.read().decode("utf-8", errors="replace")
        except Exception as exc:
            logger.warning("publicdns_info fetch failed: %s", exc)
            return []

        results: list[Candidate] = []
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            ip = row.get("ip_address", "").strip()
            if not ip:
                continue
            reliability_raw = row.get("reliability", "")
            try:
                reliability = float(reliability_raw)
            except ValueError:
                reliability = 0.0
            provider = row.get("as_org", None) or None
            meta: dict[str, str] = {}
            if reliability_raw:
                meta["reliability"] = reliability_raw
            country = row.get("country_id", "")
            if country:
                meta["country"] = country
            for transport in ("dns-udp", "dns-tcp"):
                results.append(
                    Candidate(
                        provider=provider,
                        source=self.SOURCE_NAME,
                        transport=transport,  # type: ignore[arg-type]
                        endpoint_url=None,
                        host=ip,
                        port=53,
                        path=None,
                        metadata=meta,
                    )
                )
            _ = reliability
        return results
