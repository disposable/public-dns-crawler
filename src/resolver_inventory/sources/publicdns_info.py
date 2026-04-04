"""Source adapter for public-dns.info nameserver list."""

from __future__ import annotations

import csv
import io
import urllib.request

from resolver_inventory.models import Candidate, FilteredCandidate
from resolver_inventory.sources.base import BaseSource
from resolver_inventory.util.logging import get_logger

logger = get_logger(__name__)

DEFAULT_URL = "https://public-dns.info/nameservers.csv"
DEFAULT_MIN_RELIABILITY = 0.50


class PublicDnsInfoSource(BaseSource):
    """Fetch the public-dns.info CSV and yield DNS candidates."""

    SOURCE_NAME = "publicdns_info"

    def __init__(self, entry) -> None:
        super().__init__(entry)
        self._filtered: list[FilteredCandidate] = []

    def candidates(self) -> list[Candidate]:
        self._filtered = []
        url = self.entry.url or self.entry.extra.get("url") or DEFAULT_URL
        min_reliability = self._min_reliability()
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                content = resp.read().decode("utf-8", errors="replace")
        except Exception as exc:
            msg = f"publicdns_info fetch failed: {exc}"
            logger.error(msg)
            raise RuntimeError(msg) from exc

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
            if reliability < min_reliability:
                detail = (
                    f"public-dns.info reliability {reliability:.2f} is below "
                    f"configured minimum {min_reliability:.2f}"
                )
                for transport in ("dns-udp", "dns-tcp"):
                    self._filtered.append(
                        FilteredCandidate(
                            candidate=Candidate(
                                provider=row.get("as_org", None) or None,
                                source=self.SOURCE_NAME,
                                transport=transport,  # type: ignore[arg-type]
                                endpoint_url=None,
                                host=ip,
                                port=53,
                                path=None,
                                metadata={
                                    "reliability": reliability_raw,
                                    "country": row.get("country_id", ""),
                                },
                            ),
                            reason="source_reliability_below_min",
                            detail=detail,
                            stage="source",
                        )
                    )
                continue
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
        return results

    def filtered_candidates(self) -> list[FilteredCandidate]:
        return list(self._filtered)

    def _min_reliability(self) -> float:
        raw = self.entry.extra.get("min_reliability", DEFAULT_MIN_RELIABILITY)
        try:
            return float(raw)
        except TypeError:
            logger.warning(
                "publicdns_info invalid min_reliability %r; using default %.2f",
                raw,
                DEFAULT_MIN_RELIABILITY,
            )
            return DEFAULT_MIN_RELIABILITY
        except ValueError:
            logger.warning(
                "publicdns_info invalid min_reliability %r; using default %.2f",
                raw,
                DEFAULT_MIN_RELIABILITY,
            )
            return DEFAULT_MIN_RELIABILITY
